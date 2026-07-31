# Provider and Admin Service preparation corpus (#332)

This corpus is synthetic, sanitized, and preparation-only. It freezes the
source, privacy, topology, key, evidence, coverage, and state expectations for
issue #332 without adding a production reducer or native collector.

The shared CCM parser remains the transport grammar for `Smsprov.log` and
`AdminService.log`. The scoped IIS file is supplemental W3C evidence only. It
is deliberately excluded from CCM normalization and cannot create or complete
an Admin Service transaction.

## Proposed source groups

| Source ID | Basename | Producer role | Layer | Diagnostic use |
| --- | --- | --- | --- | --- |
| `server-provider` | `Smsprov.log` | `provider` | Provider | primary CCM |
| `server-admin-service` | `AdminService.log` | `provider` | Admin Service | primary CCM |
| `server-admin-service-iis` | `u_ex_synthetic.log` | `provider` | supplemental IIS | optional context only |

`AdminService.log` retains the catalogued producer role `provider`; the
workflow layer is separately recorded as `adminService`. A filename alone
cannot invent a role, endpoint, or installed component.

## Scenario matrix

| Scenario | Layer/outcome | Conservative control |
| --- | --- | --- |
| `provider-success` | Provider terminal success | all five Provider phases are line-cited |
| `provider-authz-denied` | Provider terminal failure | explicit authorization evidence; no caller identity in public output |
| `provider-query-failure` | Provider terminal failure | operation failure is source-specific; query text is not a key |
| `provider-timeout` | Provider incomplete | invalid offset and no terminal outcome keep confidence low |
| `admin-service-success` | Admin Service terminal success | six-stage Admin Service grammar is independent |
| `admin-service-auth-failure` | Admin Service terminal failure | explicit authentication failure only |
| `admin-service-backend-failure` | Admin Service terminal failure | backend evidence does not claim client or console impact |
| `iis-supplemental` | Admin Service success plus IIS context | IIS cannot create or raise transaction confidence |
| `privacy-redaction` | distinct Provider/Admin Service successes | same request-like ID stays split by layer/endpoint; raw synthetic sensitive shapes are absent publicly |
| `rotation-boundary` | no transaction | split fragments and unknown version cannot create an exact key |
| `incomplete` | Admin Service incomplete | bounded Admin Service follow-up only |

## Contract boundaries

- Exact request identity requires a profile-validated request ID, safe
  operation handle, endpoint ID, layer, and compatible topology.
- Endpoint paths, caller identities, query text, URL parameters,
  authorization values, and same-minute timestamps are not key material.
- High confidence requires a complete captured artifact, usable timestamp
  provenance, explicit terminal evidence, exact topology, and no coverage gap.
- Missing, invalid-offset, unknown-version, partial-rotation, unsupported, and
  supplemental evidence remain coverage or source-local states.
- Every public transaction observation cites one normalized logical CCM
  record and cannot reuse or cross a Provider/Admin Service layer.
- Public expected output contains no cross-side causal claim. Any future
  correlation remains outside #332 and must satisfy #333 contracts.

The manifest/expected JSON is a proposal pending reviewed #318 and #335
interfaces. It must not be treated as an implemented native manifest.
