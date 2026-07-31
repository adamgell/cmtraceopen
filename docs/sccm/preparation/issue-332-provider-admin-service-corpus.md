# Issue #332 Provider/Admin Service preparation

## Status

This slice prepares the source and reducer contracts only. Production
extraction/reduction waits for reviewed, stable #318 and #335 interfaces. No
Windows collection, network call, SQL/WMI query, database access, Tauri
command, or live SCCM acceptance is included.

## Source contract

The existing pure Rust catalog already distinguishes:

- `Smsprov.log` as Provider-family CCM from the `provider` producer role;
- `AdminService.log` as Admin-Service-family CCM from the `provider` producer
  role.

#332 keeps producer role and workflow layer separate. The proposed
`server-provider` and `server-admin-service` source IDs preserve the exact
endpoint handle and sanitized configured-path provenance. An optional
`server-admin-service-iis` source is scoped W3C context only. An unknown or
arbitrary IIS tree stays unsupported/supplemental and cannot be promoted into
an Admin Service transaction.

## Request and privacy contract

A request transaction is derived only from this exact tuple:

~~~text
layer + normalized request ID + safe operation handle + endpoint ID
      + compatible role/topology + selected versioned extraction profile
~~~

Caller identity, authorization/token material, query text, URL parameters,
certificate details, and endpoint path are excluded from keys and public
summaries. The privacy scenario uses reserved synthetic values to prove the
private raw fixture contains sensitive-shaped input while expected public
output does not.

The Provider and Admin Service fixtures intentionally reuse the same request
ID in the privacy scenario. They remain separate because the layer,
operation, and endpoint components differ. A timestamp or endpoint alone can
never construct the exact transaction ID.

## State contracts

Provider:

~~~text
Receive -> AuthenticateOrAuthorize -> ExecuteProviderOperation
        -> Respond -> RecordOutcome
~~~

Admin Service:

~~~text
Receive -> AuthenticateOrAuthorize -> Route -> ExecuteBackendOperation
        -> Respond -> RecordOutcome
~~~

Not every source must emit every intermediate phase. Phase movement remains
monotonic. A confirmed failure requires explicit source-specific terminal
evidence; a timeout, missing response, unknown version, invalid offset, or
split rotation remains incomplete or source-local.

## Coverage and provenance

Each artifact pins:

- SCCM-specific capture state;
- producer role and opaque host handle;
- workflow layer and endpoint;
- source ID, original basename, and sanitized source path;
- collision-resistant path fingerprint;
- rotation kind, lineage, and fragment completeness;
- source version, collection time, encoding, cap, byte count, and safe
  relative path for physical evidence.

Nonphysical states may not invent physical file provenance. A complete
transaction citation must refer to captured, complete, normalized CCM
evidence from the same layer. Supplemental IIS evidence is source-local and
noncorrelatable.

## Test-first record

The first focused test failed because the exact eleven-scenario fixture root
did not exist. After the corpus was added, the privacy transaction test failed
because the public redactor correctly replaced a sensitive tail with a
redaction marker; the fixture-field reader was narrowed to recognize that
marker without weakening exact key checks.

A later mutation pass reproduced seven fail-open cases before correction:
control-bearing versions, blank rewritten artifact identity, arbitrary
transaction/source-local observation IDs, high confidence over an incomplete
fragment, arbitrary outcomes, and omitted required bounded requests. The
closed contract now rejects all seven.

## Explicit limits

- This is not a production reducer.
- This is not a native capture adapter.
- This does not prove any Provider/Admin Service role exists from a default
  path.
- This does not support broad IIS parsing.
- This does not claim client, console, API consumer, or cross-side causality.
- The in-progress SCCM Server lab is a future validation source, not current
  acceptance evidence.
