# SCCM advanced-role source-card catalog

Issue: #334

Card schema: `1.0.0`

Evidence status: synthetic contract only

This catalog is a gate for future source discovery. It does not add a parser, reducer, transaction, finding, native collector, or live Windows acceptance claim. The candidate basenames are capture-discovery hints, not assertions that a role is configured or that a file exists. Missing, denied, capped, skipped, unsupported, malformed, and partial sources remain coverage states.

## Admission contract

Every card records a stable card ID/version, role and family, candidate basenames and configured path classes, raw parser family, source-version scope, bounded capture and rotation policy, privacy classes, healthy and terminal evidence requirements, correlation policy, fixture IDs, issue ownership, semantic limits, next evidence, and supersession state.

Promotion is monotonic and evidence-bound:

| State | Required evidence | Permitted use |
| --- | --- | --- |
| `candidate` | Reviewable source mapping only | Bounded capture guidance |
| `observed` | Sanitized role, configured-path, and source-version provenance | Bounded capture guidance |
| `fixtureValidated` | Observed provenance plus success, failure, coverage, privacy, and rotation fixtures | Contract testing; no production reducer |
| `ruleValidated` | Exact key, phase, terminal, version, privacy, and incomplete-bundle tests plus a linked implementation issue | Eligible for a production semantic catalog |
| `deferred` | A precise unsupported reason and next evidence | Coverage preservation only |

Only a valid `ruleValidated` card with a linked implementation issue and named reducer can enter a semantic analyzer. Candidate, observed, fixture-validated, and deferred cards must set `captureGuidanceOnly`, cannot create transactions, and cannot create failure findings. Time-only correlation is forbidden at every state. Unknown parser or promotion values are preserved as inspectable strings and rejected deterministically rather than panicking or being silently admitted.

Public projection is restricted to nonsensitive card, role, capture, and coverage metadata. A card with privacy classes or medium/high sensitivity must require redaction, and raw sensitive field projection is always rejected.

## Initial cards

No initial card has sanitized lab-observed provenance, so none has a follow-up implementation issue or semantic admission.

| Card ID | Candidate scope | Raw grammar | State | Privacy | Exact next promotion evidence |
| --- | --- | --- | --- | --- | --- |
| `certificate-enrollment-pki` | Certificate registration point; candidate `crp.log` | CCM | `candidate` | High: certificate, device, and subject identity | Authorized role/path/version observation; success, terminal, privacy, incomplete, and rotation fixtures |
| `client-notification-bgb` | Server-side notification and management-point context; candidate `BgbServer.log` | CCM | `candidate` | High: device, user, and notification payload | Sanitized server-role observation and independently validated server-versus-client notification keys |
| `cloud-service-connection` | Service connection point and CMG connection point; candidates `CloudMgr.log`, `SMS_Cloud_ProxyConnector.log` | CCM | `candidate` | High: tenant, endpoint, certificate, and token-like data | Authorized configured-role observation followed by privacy review and bounded scenario fixtures |
| `osd-pxe` | PXE-enabled distribution point and site server; candidate `smspxe.log` | CCM | `candidate` | High: device, MAC, network, and resource identity | Sanitized configured-role observation plus topology, privacy, rejection, rotation, malformed, and incomplete fixtures |
| `reporting` | Reporting services point; candidate `srsrp.log` | CCM | `candidate` | High: report, query, account, and data-source identity | Sanitized configured-role observation and bounded redaction fixtures |
| `sql-database-export` | Explicit operator-provided database supplement | Unsupported | `deferred` | High: database, query, device, and user identity | Separately approved data-minimized export contract, authorization model, schema, and fixtures |

Candidate names must be confirmed against configured role provenance before promotion. A missing default path never proves that a role is absent or broken. Database access is not a parser fallback and is not authorized by this card.

## Determinism and lifecycle

Catalog filenames and card IDs are sorted and unique. Nested role, basename, path, privacy, version-prefix, fixture, key, and supersession lists are also sorted where ordering affects serialization or comparison. Active cards cannot name a successor. Deprecated cards must name an explicit successor, and supersession metadata cannot promote a card.

The synthetic catalog-fixture matrix proves:

- a valid candidate remains outside the semantic catalog;
- a missing required owner is rejected;
- a candidate cannot declare a production reducer or diagnostic capabilities;
- high-sensitivity data cannot disable redaction or project raw sensitive fields;
- unknown parser and promotion values are retained for review and rejected;
- deprecation without an explicit successor is rejected.

## Native validation boundary

The development SCCM Server may later provide sanitized observed provenance, but it is not a blocker for this contract and has not been exercised by this slice. Any future promotion must update the individual card with evidence IDs and fixtures, open a dedicated implementation issue, obtain review, and rerun the parser, wasm32, strict Clippy, formatting, and manifest checks before semantic admission.
